import random
import string


class Utils:
    @staticmethod
    def extendToMultipleOf2(text):
        current = 1
        while(len(text) > current):
            current *= 2
        difference = current - len(text)
        result = text + Utils.randomString(difference)
        return result

    @staticmethod
    def randomString(length):
        return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(length))
