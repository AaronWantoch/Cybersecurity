from Crypto.Random import get_random_bytes
import csv

def saveCSVFileWithData(csvColumnNames, csvRows):
    filename = "CSV/AllTimes.csv"
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