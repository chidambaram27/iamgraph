import pytest

from iamgraph import gen_iam, gen_k8s, ingest
from iamgraph.db import get_graph


@pytest.fixture(scope="session")
def g(tmp_path_factory):
    graph = get_graph("iam_test")
    data = gen_iam.write(tmp_path_factory.mktemp("data"))
    gen_k8s.write(data)
    ingest.ingest_files(graph, data)
    yield graph
    graph.delete()
