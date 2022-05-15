from display import Display
from utils import Utils

if __name__ == '__main__':
    for i in [100000]:
        Display.displayMessageAES(Utils.randomString(i))
        Display.displayMessageRSA(Utils.randomString(i), 2048)

