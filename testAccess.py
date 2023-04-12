'''Module providing os libraries for ingesting environment variables'''
import os

from prismacloud.api import pc_api

# Settings for Prisma Cloud Compute Edition

settings = {
    "url":      os.environ.get('PC_URL'),
    "identity": os.environ.get('PC_IDENTITY'),
    "secret":   os.environ.get('PC_SECRET')
}

pc_api.configure(settings)

print('Prisma Cloud API Current User:')
print()
print(pc_api.current_user())
print()
