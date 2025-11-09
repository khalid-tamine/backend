from fastapi import FastAPI, BackgroundTasks, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import base64, uuid, time
import jwt
import asyncio
import os
from dotenv import load_dotenv
load_dotenv()
# -------- CONFIGURATION -------- #
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise Exception("SECRET_KEY missing — set it in environment variables!")

ALGORITHM = os.getenv("ALGORITHM")
if not ALGORITHM:
    raise Exception("ALGORITHM missing — set it in environment variables!")


# -------- APP INITIALIZATION -------- #
app = FastAPI()
security = HTTPBearer()

# storage for background processing
TASK_RESULTS = {}

# -------- AUTHENTICATION -------- #

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

# -------- REQUEST MODELS -------- #

class ScreenPayload(BaseModel):
    screenshot: str  # base64 screenshot

# -------- BACKGROUND PROCESS -------- #

async def process_screenshot(task_id: str, screenshot_b64: str):
    # Example heavy work
    await asyncio.sleep(1)  # simulate AI processing time

    # decode image (optional)
    img_bytes = base64.b64decode(screenshot_b64)

    # TODO: add AI or rule-based logic here
    result = {
        "action": "attack",
        "reason": "Detected enemy",
        "timestamp": time.time()
    }

    TASK_RESULTS[task_id] = result

# -------- ENDPOINTS -------- #

@app.post("/send", dependencies=[Depends(verify_token)])
async def send_screenshot(payload: ScreenPayload, background: BackgroundTasks):
    task_id = str(uuid.uuid4())

    # queue processing
    background.add_task(process_screenshot, task_id, payload.screenshot)

    return {"task_id": task_id, "status": "received"}

@app.get("/result/{task_id}", dependencies=[Depends(verify_token)])
async def get_result(task_id: str):
    if task_id in TASK_RESULTS:
        return TASK_RESULTS.pop(task_id)  # return & delete from memory
    else:
        return {"status": "processing"}
