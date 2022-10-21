from asyncio import sleep
import os


if __name__=="__main__":
    os.system("python CA.py")
    sleep(1)
    os.system("python DSP.py")
    sleep(1)
    os.system("python DAP.py")
    sleep(1)
    os.system("python AU.py")

