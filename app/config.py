from pydantic import BaseModel, Field


class Settings(BaseModel):
    service_name: str = "incident-prediction-module"
    syslog_host: str = "0.0.0.0"
    syslog_port: int = 5514
    recent_predictions_limit: int = 1000
    high_risk_threshold: float = 75.0
    medium_risk_threshold: float = 45.0
    sequence_window_seconds: int = 900


settings = Settings()

