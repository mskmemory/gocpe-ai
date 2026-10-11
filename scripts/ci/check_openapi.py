"""Validate the OpenAPI contract and inline request/response examples offline."""
import json
from pathlib import Path
from jsonschema import RefResolver
from openapi_spec_validator import validate_spec
from openapi_schema_validator import OAS30Validator

spec = json.loads(Path('api/openapi.json').read_text())


def local_refs(value):
    if isinstance(value, dict):
        if '$ref' in value:
            ref = value['$ref']
            if not ref.startswith('#/'):
                raise ValueError(f'External references are not allowed in offline CI: {ref}')
            target = spec
            for token in ref[2:].split('/'):
                target = target[token.replace('~1', '/').replace('~0', '~')]
        for child in value.values():
            local_refs(child)
    elif isinstance(value, list):
        for child in value:
            local_refs(child)


local_refs(spec)
validate_spec(spec)
resolver = RefResolver.from_schema(spec)
count = 0


def examples(value):
    global count
    if isinstance(value, dict):
        if 'schema' in value:
            samples = []
            if 'example' in value:
                samples.append(value['example'])
            for example in value.get('examples', {}).values():
                if '$ref' in example:
                    _, example = resolver.resolve(example['$ref'])
                if 'externalValue' in example:
                    raise ValueError('External examples are not allowed in offline CI')
                if 'value' in example:
                    samples.append(example['value'])
            for sample in samples:
                OAS30Validator(value['schema'], resolver=resolver).validate(sample)
                count += 1
        for child in value.values():
            examples(child)
    elif isinstance(value, list):
        for child in value:
            examples(child)


examples(spec)
print(f'OpenAPI specification, local references and {count} inline examples passed')
