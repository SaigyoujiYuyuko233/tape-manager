#!/bin/python

from cleo.application import Application
from cmd import GenkeyCommand, RunCommand, MountCommand

application = Application()
application.add(GenkeyCommand())
application.add(RunCommand())
application.add(MountCommand())

if __name__ == "__main__":
    application.run()
