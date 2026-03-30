from .defender_role import DefenderRoleParser
from .defender_task import DefenderTaskParser
from .defender_format_output import DefenderOutputFormatParser
import logging


def parser_defender_scenario(defender_role_desc: str, defender_task_desc: str, defender_output_format: str = None):
    try:
        # Parser 
        role_parser = DefenderRoleParser()
        defender_role = role_parser.parse(defender_role_desc)
        task_parser = DefenderTaskParser()
        defender_task = task_parser.parse(defender_task_desc)
        defender_output = "NATURAL"
        if defender_output_format:
            task_parser = DefenderOutputFormatParser()
            defender_output = task_parser.parse(defender_output_format)
        return  {
            "defender_role": defender_role,
            "defender_task": defender_task,
            "defender_output": defender_output
        }
    except Exception as e:
        logging.error(f"Error: {e}")
        return None
