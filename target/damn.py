import numpy as np
from keras.models import load_model
import logging




def get_model():
    # print("加载模型")
    return load_model('/home/gzhuadmin/workspace/live-capture/target/m2_128.h5')

def perform_predict(model, bit_string: str) -> str:
    logging.basicConfig(level=logging.ERROR)
    # print("\n执行python脚本")
    most_important_indices = \
        [
            1, 107, 231, 25, 109, 15, 233, 0, 2, 3, 235, 4, 29, 234, 232, 199, 239, 5, 230, 16, 180, 98,
            236, 6, 31, 238, 237, 30, 24, 9, 11, 126, 13, 7, 198, 10, 43, 56, 50, 28, 608, 202, 318, 201,
            117, 8, 23, 34, 111, 12, 48, 33, 51, 32, 27, 45, 14, 46, 54, 74, 119, 40, 228, 125, 37, 224,
            35, 44, 61, 248, 118, 70, 121, 60, 49, 52, 96, 206, 17, 39, 36, 18, 38, 123, 41, 241, 57, 240,
            66, 222, 20, 122, 62, 134, 204, 42, 69, 59, 192, 229, 203, 226, 120, 65, 55, 129, 26, 130, 19,
            127, 227, 21, 99, 139, 58, 64, 68, 213, 113, 140, 135, 141, 53, 67, 200, 22, 72, 63
        ]
    label_map = {
        0: "benign",
        1: "ddos",
        2: "dos",
        3: "ftp-patator",
        4: "infiltration",
        5: "port-scan",
        6: "ssh-patator",
        7: "web-attack"
    }
    samples = list(map(int, bit_string.split(",")[1:]))
    index = np.argmax(
        model.predict(
            np.take(
                samples, most_important_indices, axis=0
            )[np.newaxis, :, np.newaxis].astype('int'),
            verbose=0
        )
    )
    # label =
    # with open("/home/linyikai/ml/nprint/example/traffic_with_port_scan.csv") as traffic:
    #     for line in traffic:
    #         samples = list(map(int, line.split(",")[1:]))
    #         index = np.argmax(
    #             model.predict(
    #                 np.take(
    #                     samples, most_important_indices, axis=0
    #                 )[np.newaxis, :, np.newaxis].astype('int'),
    #                 verbose=0
    #             )
    #         )
    #         label = label_map[int(index)]
    #         if label != "benign":
    #             print(label)
    return label_map[int(index)]