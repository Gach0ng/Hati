"""
Pentest Agent - Docker 容器隔离执行
在 Docker 容器中执行安全工具，确保隔离
"""

import os
import uuid
from typing import Dict, Any, Optional


# ===========================================
# 配置
# ===========================================
DOCKER_HOST = os.getenv("DOCKER_HOST", "unix:///var/run/docker.sock")
TOOLKIT_IMAGE = os.getenv("TOOLKIT_IMAGE", "kalilinux/kali-rolling:latest")

# 资源限制
DEFAULT_MEMORY_LIMIT = "2g"  # 2GB 内存
DEFAULT_CPU_QUOTA = 50000   # 50% CPU
DEFAULT_TIMEOUT = 300       # 5分钟超时


# ===========================================
# 容器执行器
# ===========================================
class ContainerRunner:
    """
    Docker 容器隔离执行器

    安全特性：
    - 任务级容器创建与销毁
    - 资源限制（CPU、内存）
    - 网络隔离
    - 只读文件系统
    - tmpfs 用于临时文件
    """

    def __init__(self):
        try:
            import docker
            self.client = docker.DockerClient(base_url=DOCKER_HOST)
            # 测试连接
            self.client.ping()
            print(f"✅ Docker 连接成功")
        except ImportError:
            print(f"⚠️  Docker SDK 未安装（Windows 环境，工具通过 VM MCP 执行）")
            self.client = None
        except Exception as e:
            print(f"⚠️  Docker 不可用: {e}")
            self.client = None

    def execute(
        self,
        command: str,
        image: str = TOOLKIT_IMAGE,
        memory_limit: str = DEFAULT_MEMORY_LIMIT,
        cpu_quota: int = DEFAULT_CPU_QUOTA,
        timeout: int = DEFAULT_TIMEOUT,
        network_disabled: bool = True,
        read_only: bool = True,
        tmpfs_size: str = "100m",
    ) -> Dict[str, Any]:
        """
        在容器中执行命令

        Args:
            command: 要执行的命令
            image: Docker 镜像
            memory_limit: 内存限制
            cpu_quota: CPU 配额 (100000 = 100%)
            timeout: 超时时间（秒）
            network_disabled: 是否禁用网络
            read_only: 是否只读文件系统
            tmpfs_size: tmpfs 大小

        Returns:
            执行结果
        """
        if self.client is None:
            return {
                "success": False,
                "error": "Docker 不可用",
                "stdout": "",
                "stderr": "Docker 客户端未初始化",
            }

        container_id = str(uuid.uuid4())[:8]
        container_name = f"pentest-{container_id}"

        try:
            from docker.types import HostConfig
            # 创建容器配置
            host_config = HostConfig(
                mem_limit=memory_limit,
                cpu_period=100000,
                cpu_quota=cpu_quota,
                network_mode="none" if network_disabled else "bridge",
                read_only=read_only,
                tmpfs={
                    "/tmp": f"size={tmpfs_size},mode=1777"
                },
                auto_remove=False,
            )

            # 创建并启动容器
            container = self.client.containers.run(
                image,
                f"/bin/bash -c '{command}'",
                name=container_name,
                detach=True,
                host_config=host_config,
                stdout=True,
                stderr=True,
                remove=False,
            )

            try:
                # 等待命令完成
                result = container.wait(timeout=timeout)

                # 获取输出
                stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="ignore")
                stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="ignore")

                return {
                    "success": result["StatusCode"] == 0,
                    "return_code": result["StatusCode"],
                    "stdout": stdout,
                    "stderr": stderr,
                    "container_id": container.id,
                    "container_name": container_name,
                }

            finally:
                # 确保容器被删除
                try:
                    container.remove(force=True)
                except Exception:
                    pass

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "stdout": "",
                "stderr": str(e),
            }

    def execute_with_network(
        self,
        command: str,
        image: str = TOOLKIT_IMAGE,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        在有网络连接的容器中执行命令

        Args:
            command: 要执行的命令
            image: Docker 镜像
            **kwargs: 其他参数

        Returns:
            执行结果
        """
        # 允许网络连接
        kwargs["network_disabled"] = False
        return self.execute(command, image, **kwargs)

    def pull_image(self, image: str = TOOLKIT_IMAGE) -> bool:
        """
        拉取 Docker 镜像

        Args:
            image: 镜像名称

        Returns:
            是否成功
        """
        if self.client is None:
            return False

        try:
            print(f"正在拉取镜像: {image}")
            self.client.images.pull(image)
            print(f"✅ 镜像 {image} 拉取成功")
            return True
        except Exception as e:
            print(f"❌ 镜像拉取失败: {e}")
            return False


# ===========================================
# 全局实例
# ===========================================
_container_runner: Optional[ContainerRunner] = None


def get_container_runner() -> ContainerRunner:
    """获取容器执行器实例"""
    global _container_runner
    if _container_runner is None:
        _container_runner = ContainerRunner()
    return _container_runner


# ===========================================
# 示例用法
# ===========================================
if __name__ == "__main__":
    runner = ContainerRunner()

    # 拉取镜像
    runner.pull_image()

    # 执行命令
    result = runner.execute("nmap --version")
    print(f"Success: {result['success']}")
    print(f"Output: {result['stdout']}")
