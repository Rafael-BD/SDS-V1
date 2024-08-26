import yaml
from src.detector import ScanDetector

def load_config():
    with open("config.yaml", "r") as file:
        config = yaml.safe_load(file)
    return config

def main():
    config = load_config()

    # Inicializa o detector com as configurações do config.yaml
    detector = ScanDetector(
        interface=config["interface"],
        time_window=config["time_window"],
        port_threshold=config["port_threshold"],
        fragmentation_limit=config["fragmentation_limit"]
    )
    detector.start()

if __name__ == "__main__":
    main()
