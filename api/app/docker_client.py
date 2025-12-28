import docker


def get_client():
    return docker.DockerClient(base_url="unix://var/run/docker.sock")


def list_containers():
    client = get_client()
    containers = []
    for container in client.containers.list(all=True):
        containers.append(
            {
                "id": container.id,
                "name": container.name,
                "status": container.status,
                "labels": container.labels,
                "mounts": [mount["Source"] for mount in container.attrs.get("Mounts", [])],
                "image": container.image.tags,
            }
        )
    return containers


def list_volumes():
    client = get_client()
    volumes = []
    for volume in client.volumes.list():
        volumes.append(
            {
                "name": volume.name,
                "driver": volume.attrs.get("Driver"),
                "labels": volume.attrs.get("Labels"),
                "mountpoint": volume.attrs.get("Mountpoint"),
            }
        )
    return volumes
