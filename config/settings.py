import os
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("3c6844754bd54a9bc155ad8c6c8912adb68383aa374ff850df02faf02137a986", "").strip()
