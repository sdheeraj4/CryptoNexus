from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from pydantic import BaseModel, Field, field_validator

from app.ai.inference import ModelUnavailable, Prediction, predict_crypto_behavior
from app.analysis import AnalysisRequest, analyze
from app.sandbox import SandboxRequest, SandboxResult, run_sandbox

from app.errors import register_error_handlers
from app.logging_config import configure_logging
from app.uploads import ScanResult, MAX_UPLOAD_BYTES, process_upload

configure_logging()
app = FastAPI(title="CryptoNexus", version="0.1.0")
register_error_handlers(app)


class RequestSizeLimit:
    """Bound the multipart body before FastAPI spools uploaded files to disk."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit = MAX_UPLOAD_BYTES + 1024 * 1024  # Allow multipart framing.
        headers = dict(scope.get("headers", []))
        try:
            length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            return await JSONResponse({"error": "Invalid Content-Length."}, 400)(scope, receive, send)
        if length > limit:
            return await JSONResponse({"error": "Request exceeds the 21 MiB limit."}, 413)(scope, receive, send)
        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            received += len(message.get("body", b""))
            if received > limit:
                raise HTTPException(413, "Request exceeds the 21 MiB limit.")
            return message

        await self.app(scope, limited_receive, send)


app.add_middleware(RequestSizeLimit)


@app.get("/health")
def health():
    return {"status": "ok", "service": "CryptoNexus"}


@app.post("/api/upload", response_model=ScanResult)
def upload_repository(file: UploadFile = File(...)):
    return process_upload(file)


class ClassificationRequest(BaseModel):
    code: str = Field(min_length=1, max_length=16_000)
    context: str = Field(default="", max_length=8_000)
    language: str = Field(default="unknown", max_length=32)

    @field_validator("code")
    @classmethod
    def nonempty_code(cls, value):
        if not value.strip():
            raise ValueError("code must not be blank")
        return value


@app.post("/api/ai/classify", response_model=Prediction)
def classify(request: ClassificationRequest):
    try:
        return predict_crypto_behavior(request.code, request.context, request.language)
    except ModelUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc


@app.post("/api/analyze")
def analyze_repository(file: UploadFile = File(...)):
    scan = process_upload(file)
    return analyze(AnalysisRequest.model_validate(scan.model_dump()))


@app.post("/api/sandbox/run", response_model=SandboxResult)
def sandbox(request: SandboxRequest):
    return run_sandbox(request)


# Register after API routes so /docs and /api/* retain their existing handlers.
FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"
if FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
