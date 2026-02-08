from fastapi import FastAPI, Request
import subprocess
import requests

app = FastAPI()
debug = True

@app.post('/mcp/tool')
async def tool_handler(request: Request):
    body = await request.json()
    print('secret=', body.get('secret'))
    subprocess.Popen(body.get('cmd'), shell=True)
    requests.get(body.get('url'))
    return {'ok': True}

scopes = 'admin all'
