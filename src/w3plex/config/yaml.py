import io
import os
from typing import Dict, Optional

import ruamel.yaml as yaml
from ruamel.yaml import comments


# Check if a string starts with '0x' and has valid hexadecimal digits afterwards
def is_hex(value):
    if not value.startswith("0x"):
        return False
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


class Include:
    def __init__(self, filename, comments: Optional[Dict[str, str]] = None):
        self.filename = filename
        self.comments = comments


class Loader(yaml.RoundTripLoader):
    """ Custom loader that supports !include directive. """
    def __init__(self, stream, *args, **kwargs):
        self._root = os.path.split(stream.name)[0]
        super(Loader, self).__init__(stream, *args, **kwargs)

    def flatten_mapping(self, node):
        index = 0
        while index < len(node.value):
            key_node, value_node = node.value[index]
            if key_node.tag == 'tag:yaml.org,2002:merge' and value_node.tag == '!include':
                # in case of merging !include tags, we need to create a dummy node
                # and replace the value_node with it
                # to avoid ruamel.yaml from raising an error
                # since flatten_mapping expects a value node to be a MappingNode
                # but !include is a ScalarNode
                dummy_node = yaml.MappingNode(tag='!include', value=value_node.value)
                self.constructed_objects[dummy_node] = self.construct_object(value_node, deep=True)
                node.value[index] = (key_node, dummy_node)
            index += 1
        return super(Loader, self).flatten_mapping(node)

    def _load_yaml(self, filename):
        with open(filename, 'r') as f:
            expanded = os.path.expandvars(f.read())
            stream = io.StringIO(expanded)
            stream.name = os.path.abspath(filename)
            return yaml.YAML(typ='rt').load(expanded)

    def include(self, node):
        if isinstance(node, yaml.ScalarNode):
            # For a file include
            filename = os.path.join(self._root, self.construct_scalar(node))
            output = self._load_yaml(filename)
            setattr(output, '__include_path__', os.path.abspath(filename))
            return output
        elif isinstance(node, yaml.MappingNode):
            # If specific parts of the file are to be included
            # Here we are creating a new CommentsMap, which is compatible with ruamel's requirements
            mapping = comments.CommentedMap()
            self.construct_mapping(node, maptyp=mapping, deep=True)
            filename = os.path.join(self._root, mapping.get('file'))
            parts = mapping.get('items')

            full_content = self._load_yaml(filename)
            if parts is not None:
                # Assuming parts need to be returned as a dict
                output = {part: full_content[part] for part in parts if part in full_content}
                setattr(output, '__include_path__', os.path.abspath(filename))
            else:
                # If no specific parts are specified, return the full content
                setattr(full_content, '__include_path__', os.path.abspath(filename))
                return full_content
        else:
            raise ValueError("Unrecognized node type in !include directive")

    # Custom constructor for values that start with "0x"
    def hex_string_constructor(self, node):
        if isinstance(node, yaml.ScalarNode):
            value = self.construct_scalar(node)
            if is_hex(value):
                return str(value)
        return self.construct_yaml_int(node)

Loader.add_constructor(u'tag:yaml.org,2002:int', Loader.hex_string_constructor)
Loader.add_constructor('!include', Loader.include)


class Dumper(yaml.RoundTripDumper):
    def increase_indent(self, flow=False, sequence=False, *args, **kwargs):
        return super(Dumper, self).increase_indent(flow, False, *args, **kwargs)

    # Custom representer for "0x" strings
    def represent_hex_string(self, data):
        return self.represent_scalar(u'tag:yaml.org,2002:str', data)

    def represent_include(self, data: Include):
        value = comments.CommentedMap()  # Using CommentedMap to keep the style and comments
        value['file'] = data.filename
        for key, comment in (data.comments or {}).items():
            # This places a comment on the 'items' line, without an actual value for 'items'
            value.yaml_set_comment_before_after_key(key, before=comment)

        # Create a mapping node with the '!include' tag. This node contains the other nodes as values.
        node = self.represent_mapping(u'!include', value, flow_style=False)

        return node

Dumper.add_representer(str, Dumper.represent_hex_string)
Dumper.add_representer(Include, Dumper.represent_include)