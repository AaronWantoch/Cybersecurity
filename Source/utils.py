import random
import string


class Utils:
    @staticmethod
    def extendToMultipleOf2(text):
        current = 1
        while(len(text) > current):
            current *= 2
        difference = current - len(text)
        result = text + ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(difference))
        return result
