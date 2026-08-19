"""System resource stats for the Console page (CPU / memory / disk)."""
import psutil


def get_system_stats() -> dict:
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.2),
        "cpu_count": psutil.cpu_count(),
        "memory_percent": vm.percent,
        "memory_used_mb": round(vm.used / (1024 * 1024), 1),
        "memory_total_mb": round(vm.total / (1024 * 1024), 1),
        "disk_percent": disk.percent,
    }
