import loguru
from kink import inject, di
import requests


class checkEnv:
    def __init__(self, min_memory=256, need_camera=False):
        self.min_memory = min_memory
        self.need_camera = need_camera
        try:
            loguru.logger.warning("开始环境检查")
            loguru.logger.debug('-' * 32)
            self.checkCamera()
            self.checkMemory()
            self.checkNetwork()
            loguru.logger.debug('-' * 32)
            loguru.logger.success("环境检查通过")
        except Exception as e:
            loguru.logger.debug('-' * 32)
            loguru.logger.error("环境检查失败")
            exit(0)

    @inject
    def checkNetwork(self, proxy: str):
        """
        检查网络环境是否正常，支持代理。

        :param proxy: 代理服务器的 URL
        :return: 网络环境是否正常
        """
        # Primeiro verificar DNS, ver se consegue resolver endereço do Baidu
        import socket
        try:
            ip = socket.gethostbyname("www.baidu.com")
            loguru.logger.info(f"DNS: www.baidu.com -> {ip}")
        except Exception as e:
            loguru.logger.error("DNS解析失败，请检查网络环境")
            raise Exception("DNS解析失败，请检查网络环境")
        loguru.logger.success("DNS正常")

        try:
            requests.get("http://www.baidu.com")
            loguru.logger.success("通联国内互联网正常")
        except Exception as e:
            raise Exception("实际通联网络环境测试异常")
        try:
            if proxy:
                loguru.logger.info('使用代理')
                cn_res = requests.get("http://www.baidu.com", proxies={"http": proxy, "https": proxy})
                loguru.logger.success("通联国内互联网代理正常")
                if len(cn_res.content) < 1:
                    loguru.logger.error(f"通联国内互联网代理异常 length:{len(cn_res.content)}")
                    raise Exception("通联国内互联网代理异常")
                res = requests.get("http://www.google.com", proxies={"http": proxy, "https": proxy})
                if len(res.content) < 1:
                    loguru.logger.error(f"通联国外互联网代理异常 length:{len(res.content)}")
                    raise Exception("通联国外互联网代理异常")
                loguru.logger.success(f"通联国外互联网代理正常 length:{len(res.content)}")
        except Exception as e:
            loguru.logger.error("通联网络环境代理测试异常")
            raise Exception("实际通联网络环境代理测试异常")
        # Obter informações da placa de rede
        import psutil
        net = psutil.net_if_addrs()
        for k, v in net.items():
            for item in v:
                if item.family == 2:
                    loguru.logger.info(f"Network: {k} {item.address}")
                    break
        loguru.logger.success("网络环境正常")

    def checkCamera(self):
        if self.need_camera:
            import cv2
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                loguru.logger.error("Não é possível abrir a câmera")
                raise Exception("Não é possível abrir a câmera")
            # Obter resolução da câmera e número total de câmeras
            width = cap.get(cv2.CAP_PROP_FRAME_WIDTH)
            height = cap.get(cv2.CAP_PROP_FRAME_HEIGHT)
            # Obter número total de câmeras no sistema
            count = 0
            while True:
                test_cap = cv2.VideoCapture(count)
                if not test_cap.isOpened():
                    break
                test_cap.release()
                count += 1
            loguru.logger.info(f"Camera: {width}x{height}, {count} cameras")
            # Tirar uma foto
            loguru.logger.info("Testando câmera...")
            ret, frame = cap.read()
            if not ret or frame is None:
                loguru.logger.error("Câmera não consegue tirar foto")
                raise Exception("Câmera não consegue tirar foto")
            loguru.logger.success("Câmera normal")
            cap.release()  # Liberar câmera

    def checkMemory(self):
        import psutil
        memory = psutil.virtual_memory().total / 1024 / 1024
        current_used_memory = psutil.virtual_memory().used / 1024 / 1024
        if memory-current_used_memory < self.min_memory:
            loguru.logger.error(f"Memória insuficiente {self.min_memory}MB, memória restante atual {memory - current_used_memory}MB")
            raise Exception("Memória insuficiente")
        used_rate = current_used_memory / memory * 100
        loguru.logger.info(f"Memory: {current_used_memory}/{memory}MB {used_rate}%")
        loguru.logger.success("Memória normal")


if __name__ == '__main__':
    di["proxy"] = "https://huancun:ylq123..@home.hc26.org:5422"
    checkEnv(need_camera=True, min_memory=256)
