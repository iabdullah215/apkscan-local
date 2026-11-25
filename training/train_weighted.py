"""mlx_lm.lora with a decision-weighted loss.

The first answer token decides between "[]" (clean) and "[" (findings follow). With plain
token-averaged cross-entropy it gets about 1/140 of an example's weight, and run v1 learned
the JSON content but not the decision (it answered [] everywhere). This wrapper gives that
token FIRST_TOKEN_WEIGHT times the weight of other answer tokens. Everything else is stock
mlx_lm.lora (same CLI and config file).

Usage: python train/train_weighted.py -c train/lora_config_v2.yaml
"""

import functools
import os

import mlx.core as mx
import mlx.nn as nn
import mlx_lm.lora as lora
from mlx_lm.tuner import trainer

W = float(os.environ.get("FIRST_TOKEN_WEIGHT", "10"))
# how many leading answer tokens get the extra weight: 1 for the finder ("[" vs "[]"),
# 5 for the verifier ({"real": true|false -> the decision is the 4th token)
K = int(os.environ.get("FIRST_TOKENS", "1"))


def weighted_loss(model, batch, lengths):
    inputs, targets = batch[:, :-1], batch[:, 1:]
    logits = model(inputs)
    steps = mx.arange(1, targets.shape[1] + 1)
    mask = mx.logical_and(steps >= lengths[:, 0:1], steps <= lengths[:, 1:])
    # target index j predicts token j+1; the first answer token sits at the offset
    first = mx.logical_and(steps >= lengths[:, 0:1], steps < lengths[:, 0:1] + K)
    w = mask.astype(mx.float32) + (W - 1.0) * first.astype(mx.float32)
    ce = nn.losses.cross_entropy(logits, targets).astype(mx.float32) * w
    return ce.sum() / w.sum(), mask.sum()


lora.train = functools.partial(trainer.train, loss=weighted_loss)
lora.evaluate = functools.partial(trainer.evaluate, loss=weighted_loss)

if __name__ == "__main__":
    print(f"decision-weighted loss: first {K} answer token(s) weight {W}")
    lora.main()
