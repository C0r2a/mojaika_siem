from collections import deque

from app.config import settings
from app.models import Prediction


class PredictionStore:
    def __init__(self) -> None:
        self._items: deque[Prediction] = deque(maxlen=settings.recent_predictions_limit)

    def add(self, prediction: Prediction) -> None:
        self._items.appendleft(prediction)

    def recent(self, limit: int = 50) -> list[Prediction]:
        return list(self._items)[:limit]


prediction_store = PredictionStore()

