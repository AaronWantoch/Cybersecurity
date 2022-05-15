from Crypto.Random import get_random_bytes
import csv
import matplotlib.pyplot as plt
import pandas as pd


def saveCSVFileWithData(filename, csvColumnNames, csvRows):
    # writing to csv file
    with open(filename, 'w') as csvfile:
        # creating a csv writer object
        csvwriter = csv.writer(csvfile)
        # writing the fields
        csvwriter.writerow(csvColumnNames)
        # writing the data rows
        csvwriter.writerows(csvRows)


def calcTimeForCipherMode(func, modeName):
    # initializing the rows list
    csvRows = []

    print("ModeName: " + modeName)
    for i in range(16, 32 + 1, 8):
        print("KeyLength:", i)
        key = get_random_bytes(i)  # value must be 16 bytes(128 bits), 24 bytes (192 bits) or 32 bytes (256 bits)
        init_vector = get_random_bytes(16)

        if(modeName in ["CFB", "CTR", "OFB"]):
            enc_time, dec_time = func(key, init_vector)
        else:
            enc_time, dec_time = func(key)

        csvRows.append([modeName, str(i), str(enc_time), str(dec_time)])  # save to main CSV array

    print('\n')
    return csvRows

def generatePlot(FeatureName, df):
    plt.clf()  # Clear figure --> prepare plt for new plot
    numberOfCipherModes = 5
    numberOfKeyLengths = 3
    for i in range(numberOfCipherModes):
        begin_ind = i * numberOfKeyLengths
        end_ind = begin_ind + numberOfKeyLengths
        lab = str(df.ModeName[begin_ind])
        dotSize = 40
        if FeatureName == "Encryption":
            plt.scatter(df[begin_ind:end_ind].KeyLength, df[begin_ind:end_ind].EncTime, label=lab, s=dotSize)
        else:
            plt.scatter(df[begin_ind:end_ind].KeyLength, df[begin_ind:end_ind].DecTime, label=lab, s=dotSize)
    plt.legend(bbox_to_anchor=(1, 1), loc="upper left")
    plt.title(FeatureName + " time with various block cipher modes")
    plt.xlabel("Key length")
    plt.ylabel("Time [s]")
    return plt


def generateEncDecPlots(csvFileName, csvColumnNames):
    plt.rcParams["figure.autolayout"] = True
    df = pd.read_csv(csvFileName, usecols=csvColumnNames)
    print("Contents in csv file:\n", df)
    encPlot = generatePlot("Encryption", df)
    encPlot.savefig("Plots/Encryption_1.png")
    decPlot = generatePlot("Decryption", df)
    encPlot.savefig("Plots/Decryption_1.png")
