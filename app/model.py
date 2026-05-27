import random

def predict_attack(features):
    if sum(features) % 2 == 0:
        return "ATTACK", random.uniform(70,95)
    return "BENIGN", random.uniform(50,80)