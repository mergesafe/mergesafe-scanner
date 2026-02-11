// packages/rules/src/js_taint.ts
import { parse } from "@babel/parser";
import traverse from "@babel/traverse";
import type { NodePath } from "@babel/traverse";
import * as t from "@babel/types";

export type RuleId = "MS002" | "MS003";
export type Severity = "critical" | "high";

export type TaintFinding = {
  ruleId: RuleId;
  message: string;
  severity: Severity;
  filePath: string;
  line: number;
  column: number;
  sink: string;
  taintedArgIndex: number;
};

type Binding =
  | { kind: "moduleNamed"; module: string; exportName: string }
  | { kind: "moduleNamespace"; module: string };

type ScopeState = {
  tainted: Map<string, boolean>;
  bindings: Map<string, Binding>;
};

const CMD_SINKS = new Set([
  "exec",
  "execSync",
  "spawn",
  "spawnSync",
  "fork",
  "execFile",
  "execFileSync",
]);

const FS_SINKS = new Set(["writeFileSync", "writeFile", "appendFile", "createWriteStream"]);

const REQ_FIELDS = new Set(["query", "body", "params", "headers"]);
const MODULES_WE_CARE = new Set(["fs", "child_process", "url"]);

function getLoc(n: t.Node) {
  const loc = n.loc?.start;
  return {
    line: loc?.line ?? 1,
    column: loc?.column ?? 0,
  };
}

// (kept; harmless even if unused)
function litStr(node: t.Node | null | undefined): string | null {
  if (!node) return null;
  if (t.isStringLiteral(node)) return node.value;
  return null;
}

// (kept; harmless even if unused)
function isIdentifierNamed(node: t.Node | null | undefined, name: string) {
  return !!node && t.isIdentifier(node) && node.name === name;
}

function memberPropName(node: t.MemberExpression | t.OptionalMemberExpression): string | null {
  if (t.isIdentifier(node.property) && !node.computed) return node.property.name;
  if (t.isStringLiteral(node.property) && node.computed) return node.property.value;
  return null;
}

function isRequireCall(node: t.Node | null | undefined): node is t.CallExpression {
  return (
    !!node &&
    t.isCallExpression(node) &&
    t.isIdentifier(node.callee) &&
    node.callee.name === "require" &&
    node.arguments.length >= 1 &&
    t.isStringLiteral(node.arguments[0])
  );
}

function moduleFromRequire(node: t.CallExpression): string {
  return (node.arguments[0] as t.StringLiteral).value;
}

function isReqMemberSource(node: t.MemberExpression | t.OptionalMemberExpression): boolean {
  const prop = memberPropName(node);
  if (!prop || !REQ_FIELDS.has(prop)) return false;
  return t.isIdentifier(node.object) && node.object.name === "req";
}

function isUrlParseQuerySource(
  node: t.MemberExpression | t.OptionalMemberExpression,
  getBinding: (name: string) => Binding | null
): boolean {
  // url.parse(req.url, true).query
  const prop = memberPropName(node);
  if (prop !== "query") return false;

  const obj = node.object;
  if (!t.isCallExpression(obj)) return false;

  const callee = obj.callee;
  if (!t.isMemberExpression(callee) && !t.isOptionalMemberExpression(callee)) return false;

  const calleeProp = memberPropName(callee);
  if (calleeProp !== "parse") return false;

  const base = callee.object;
  if (!t.isIdentifier(base)) return false;

  const b = getBinding(base.name);
  const isUrlObj = base.name === "url" || (b?.kind === "moduleNamespace" && b.module === "url");
  if (!isUrlObj) return false;

  const arg0 = obj.arguments[0];
  if (!arg0) return false;

  // req.url
  return (
    t.isMemberExpression(arg0) &&
    t.isIdentifier(arg0.object) &&
    arg0.object.name === "req" &&
    t.isIdentifier(arg0.property) &&
    arg0.property.name === "url"
  );
}

function isNewUrlSearchParamsGetCall(node: t.CallExpression): boolean {
  // new URL(req.url, ...).searchParams.get(...)
  const callee = node.callee;
  if (!t.isMemberExpression(callee) && !t.isOptionalMemberExpression(callee)) return false;

  const getProp = memberPropName(callee);
  if (getProp !== "get") return false;

  const sp = callee.object;
  if (!t.isMemberExpression(sp) && !t.isOptionalMemberExpression(sp)) return false;

  const spProp = memberPropName(sp);
  if (spProp !== "searchParams") return false;

  const base = sp.object;
  if (!t.isNewExpression(base)) return false;
  if (!t.isIdentifier(base.callee) || base.callee.name !== "URL") return false;

  const firstArg = base.arguments[0];
  if (!firstArg) return false;

  return (
    t.isMemberExpression(firstArg) &&
    t.isIdentifier(firstArg.object) &&
    firstArg.object.name === "req" &&
    t.isIdentifier(firstArg.property) &&
    firstArg.property.name === "url"
  );
}

function makeFinding(
  filePath: string,
  node: t.Node,
  ruleId: RuleId,
  sink: string,
  taintedArgIndex: number
): TaintFinding {
  const { line, column } = getLoc(node);
  if (ruleId === "MS002") {
    return {
      ruleId,
      message: "Command execution from user-controlled input",
      severity: "critical",
      filePath,
      line,
      column,
      sink,
      taintedArgIndex,
    };
  }
  return {
    ruleId,
    message: "Filesystem write with user-controlled path",
    severity: "high",
    filePath,
    line,
    column,
    sink,
    taintedArgIndex,
  };
}

export function scanJsTaint(code: string, filePath: string): TaintFinding[] {
  const findings: TaintFinding[] = [];

  const ast = parse(code, {
    sourceType: "unambiguous",
    plugins: ["typescript", "jsx"],
    errorRecovery: true,
    allowReturnOutsideFunction: true,
    ranges: false,
  });

  const scopeStack: ScopeState[] = [{ tainted: new Map(), bindings: new Map() }];

  const current = () => scopeStack[scopeStack.length - 1];

  const getBinding = (name: string): Binding | null => {
    for (let i = scopeStack.length - 1; i >= 0; i--) {
      const b = scopeStack[i].bindings.get(name);
      if (b) return b;
    }
    return null;
  };

  const isIdentTainted = (name: string): boolean => {
    for (let i = scopeStack.length - 1; i >= 0; i--) {
      const v = scopeStack[i].tainted.get(name);
      if (v === true) return true;
      if (v === false) return false;
    }
    return false;
  };

  const setIdentTainted = (name: string, v: boolean) => {
    current().tainted.set(name, v);
  };

  const setBinding = (name: string, b: Binding) => {
    current().bindings.set(name, b);
  };

  const exprIsTainted = (node: t.Node | null | undefined): boolean => {
    if (!node) return false;

    // direct sources
    if (t.isCallExpression(node) && isNewUrlSearchParamsGetCall(node)) return true;

    if (t.isIdentifier(node)) return isIdentTainted(node.name);

    if (t.isMemberExpression(node) || t.isOptionalMemberExpression(node)) {
      if (isReqMemberSource(node)) return true;
      if (isUrlParseQuerySource(node, getBinding)) return true;

      // propagation: if base is tainted, member read is tainted
      if (exprIsTainted(node.object as any)) return true;

      return false;
    }

    if (t.isBinaryExpression(node) && node.operator === "+") {
      return exprIsTainted(node.left) || exprIsTainted(node.right);
    }

    if (t.isTemplateLiteral(node)) {
      return node.expressions.some(exprIsTainted);
    }

    if (t.isConditionalExpression(node)) {
      return exprIsTainted(node.consequent) || exprIsTainted(node.alternate);
    }

    if (t.isLogicalExpression(node)) {
      return exprIsTainted(node.left) || exprIsTainted(node.right);
    }

    // V0: do not taint call returns except explicit sources above
    return false;
  };

  const markPatternTaint = (
    id: t.LVal | t.VoidPattern,
    v: boolean,
    initWasTainted: boolean
  ) => {
    if (t.isVoidPattern(id)) return;

    if (t.isIdentifier(id)) {
      setIdentTainted(id.name, v);
      return;
    }

    if (t.isObjectPattern(id) && initWasTainted) {
      for (const prop of id.properties) {
        if (t.isObjectProperty(prop)) {
          const val = prop.value;
          if (t.isIdentifier(val)) setIdentTainted(val.name, true);
        } else if (t.isRestElement(prop) && t.isIdentifier(prop.argument)) {
          setIdentTainted(prop.argument.name, true);
        }
      }
    }
  };

  const resolveCallSink = (
    callee: t.Expression | t.V8IntrinsicIdentifier
  ): { ruleId: RuleId; sink: string } | null => {
    if (t.isIdentifier(callee)) {
      const name = callee.name;

      if (CMD_SINKS.has(name)) return { ruleId: "MS002", sink: name };
      if (FS_SINKS.has(name)) return { ruleId: "MS003", sink: name };

      const b = getBinding(name);
      if (b?.kind === "moduleNamed") {
        if (b.module === "child_process" && CMD_SINKS.has(b.exportName))
          return { ruleId: "MS002", sink: `${b.module}.${b.exportName}` };
        if (b.module === "fs" && FS_SINKS.has(b.exportName))
          return { ruleId: "MS003", sink: `${b.module}.${b.exportName}` };
      }
      return null;
    }

    if (t.isMemberExpression(callee) || t.isOptionalMemberExpression(callee)) {
      const prop = memberPropName(callee);
      if (!prop) return null;

      if (t.isCallExpression(callee.object) && isRequireCall(callee.object)) {
        const mod = moduleFromRequire(callee.object);
        if (mod === "child_process" && CMD_SINKS.has(prop))
          return { ruleId: "MS002", sink: `${mod}.${prop}` };
        if (mod === "fs" && FS_SINKS.has(prop))
          return { ruleId: "MS003", sink: `${mod}.${prop}` };
      }

      if (t.isIdentifier(callee.object)) {
        const objName = callee.object.name;
        const b = getBinding(objName);

        const isFs = objName === "fs" || (b?.kind === "moduleNamespace" && b.module === "fs");
        const isChild =
          objName === "child_process" ||
          (b?.kind === "moduleNamespace" && b.module === "child_process");

        if (isChild && CMD_SINKS.has(prop)) return { ruleId: "MS002", sink: `${objName}.${prop}` };
        if (isFs && FS_SINKS.has(prop)) return { ruleId: "MS003", sink: `${objName}.${prop}` };
      }

      if (
        (t.isMemberExpression(callee.object) || t.isOptionalMemberExpression(callee.object)) &&
        t.isIdentifier(callee.object.object) &&
        (callee.object.object.name === "fs" ||
          (getBinding(callee.object.object.name)?.kind === "moduleNamespace" &&
            getBinding(callee.object.object.name)?.module === "fs"))
      ) {
        const midProp = memberPropName(callee.object);
        if (midProp === "promises" && (prop === "writeFile" || prop === "appendFile")) {
          return { ruleId: "MS003", sink: `fs.promises.${prop}` };
        }
      }
    }

    return null;
  };

  // Runtime interop fix:
  // In some ESM/CJS combos, @babel/traverse comes through as { default: fn }.
  const traverseFn =
    (((traverse as any).default ?? traverse) as unknown) as (node: any, visitors: any) => void;

  traverseFn(ast, {
    Program: {
      enter() {
        // already pushed
      },
      exit() {
        // noop
      },
    },

    Function: {
      enter() {
        scopeStack.push({ tainted: new Map(), bindings: new Map() });
      },
      exit() {
        scopeStack.pop();
      },
    },

    BlockStatement: {
      enter(path: NodePath<t.BlockStatement>) {
        if (path.parent && (t.isFunction(path.parent) || t.isCatchClause(path.parent))) return;
        scopeStack.push({ tainted: new Map(), bindings: new Map() });
      },
      exit(path: NodePath<t.BlockStatement>) {
        if (path.parent && (t.isFunction(path.parent) || t.isCatchClause(path.parent))) return;
        scopeStack.pop();
      },
    },

    ImportDeclaration(path: NodePath<t.ImportDeclaration>) {
      const mod = path.node.source.value;
      if (!MODULES_WE_CARE.has(mod)) return;

      for (const s of path.node.specifiers) {
        if (t.isImportSpecifier(s)) {
          const imported = t.isIdentifier(s.imported) ? s.imported.name : s.imported.value;
          setBinding(s.local.name, { kind: "moduleNamed", module: mod, exportName: imported });
        } else if (t.isImportNamespaceSpecifier(s)) {
          setBinding(s.local.name, { kind: "moduleNamespace", module: mod });
        } else if (t.isImportDefaultSpecifier(s)) {
          setBinding(s.local.name, { kind: "moduleNamespace", module: mod });
        }
      }
    },

    VariableDeclarator(path: NodePath<t.VariableDeclarator>) {
      const { id, init } = path.node;

      if (isRequireCall(init)) {
        const mod = moduleFromRequire(init);
        if (MODULES_WE_CARE.has(mod)) {
          if (t.isIdentifier(id)) {
            setBinding(id.name, { kind: "moduleNamespace", module: mod });
          } else if (t.isObjectPattern(id)) {
            for (const p of id.properties) {
              if (!t.isObjectProperty(p)) continue;
              const key = p.key;
              const local = p.value;
              const exportName =
                t.isIdentifier(key) ? key.name : t.isStringLiteral(key) ? key.value : null;
              if (!exportName) continue;
              if (t.isIdentifier(local)) {
                setBinding(local.name, { kind: "moduleNamed", module: mod, exportName });
              }
            }
          }
        }
        return;
      }

      const initTainted = exprIsTainted(init as any);
      if (initTainted) {
        markPatternTaint(id, true, true);
      }
    },

    AssignmentExpression(path: NodePath<t.AssignmentExpression>) {
      if (path.node.operator !== "=") return;
      const left = path.node.left;
      const right = path.node.right;
      if (exprIsTainted(right)) {
        if (t.isIdentifier(left)) setIdentTainted(left.name, true);
      }
    },

    CallExpression(path: NodePath<t.CallExpression>) {
      const sink = resolveCallSink(path.node.callee as any);
      if (!sink) return;

      for (let i = 0; i < path.node.arguments.length; i++) {
        const arg = path.node.arguments[i];
        if (t.isSpreadElement(arg)) {
          if (exprIsTainted(arg.argument)) {
            findings.push(makeFinding(filePath, path.node, sink.ruleId, sink.sink, i));
            return;
          }
        } else {
          if (exprIsTainted(arg as any)) {
            findings.push(makeFinding(filePath, path.node, sink.ruleId, sink.sink, i));
            return;
          }
        }
      }
    },
  });

  return findings;
}
