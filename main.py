#!/bin/python

from cleo.application import Application
from cmd import GenkeyCommand

application = Application()
application.add(GenkeyCommand())

if __name__ == "__main__":
    application.run()
