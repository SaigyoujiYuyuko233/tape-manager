#!/bin/python

from cleo.application import Application
from cmd import GenkeyCommand, RunCommand

application = Application()
application.add(GenkeyCommand())
application.add(RunCommand())

if __name__ == "__main__":
    application.run()
