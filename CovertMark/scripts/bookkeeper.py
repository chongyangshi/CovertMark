from ..data import retrieve

# Delete dormant entries in MongoDB and list the current stored traces.

retriever = retrieve.Retriever()
collections = retriever.list()
for collection in collections:
    retriever.select(collection['name'])

print(retriever.list(True))
