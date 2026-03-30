from .defender_role import DefenderRoleParser
from .defender_task import DefenderTaskParser
import logging


def parser_defender_scenario(defender_role_desc, defender_task_desc):
    try:
        # Parser 
        role_parser = DefenderRoleParser()
        defender_role = role_parser.parse(defender_role_desc)
        task_parser = DefenderTaskParser()
        defender_task = task_parser.parse(defender_task_desc)
        return  {
            "defender_role": defender_role,
            "defender_task": defender_task,
        }
    except Exception as e:
        logging.error(f"Error: {e}")
        return None
