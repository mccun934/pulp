# -*- coding: utf-8 -*-

# Copyright © 2010-2012 Red Hat, Inc.
#
# This software is licensed to you under the GNU General Public
# License as published by the Free Software Foundation; either version
# 2 of the License (GPLv2) or (at your option) any later version.
# There is NO WARRANTY for this software, express or implied,
# including the implied warranties of MERCHANTABILITY,
# NON-INFRINGEMENT, or FITNESS FOR A PARTICULAR PURPOSE. You should
# have received a copy of GPLv2 along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

import logging
import traceback
import os
import sys
from optparse import OptionParser, SUPPRESS_HELP

from pulp.server.db import connection

# the db connection and auditing need to be initialied before any further
# imports since the imports execute initialization code relying on the
# db/auditing to be setup
connection.initialize()

_log = logging.getLogger('pulp')

from pulp.plugins.loader.api import load_content_types
from pulp.plugins.types.database import all_type_definitions, get_unapplied_migrations
from pulp.server.db.migrate.validate import validate
from pulp.server.db.migrate.versions import get_migration_modules
from pulp.server.db.version import (
    VERSION, get_version_in_use, set_version, is_validated, set_validated,
    revert_to_version, clean_db)


class DataError(Exception):
    pass


def parse_args():
    parser = OptionParser()
    parser.add_option('--force', action='store_true', dest='force',
                      default=False, help=SUPPRESS_HELP)
    parser.add_option('--from', dest='start', default=None,
                      help='Run the migration starting at the version passed in')
    parser.add_option('--test', action='store_true', dest='test',
                      default=False,
                      help='Run migration, but do not update version')
    parser.add_option('--log-file', dest='log_file',
                      default='/var/log/pulp/db.log',
                      help='File for log messages')
    parser.add_option('--log-level', dest='log_level', default='info',
                      help='Level of logging (debug, info, error, critical)')
    options, args = parser.parse_args()
    if args:
        parser.error('unknown arguments: %s' % ', '.join(args))
    return options

def start_logging(options):
    level = getattr(logging, options.log_level.upper(), logging.INFO)
    logger = logging.getLogger('pulp') # imitate the pulp log handler
    logger.setLevel(level)
    handler = logging.FileHandler(options.log_file)
    logger.addHandler(handler)

def migrate_database_type_models(options):
    all_typedefs = all_type_definitions()
    for typedef in all_typedefs:
        migrations_to_apply = get_unapplied_migrations(typedef)
        if not migrations_to_apply:
            print 'No migrations to apply for %s.'%typedef
            continue

        # Do the migrations, yo
        for migration_module in migrations_to_apply:
            migration_module.migrate()

        # Next, we want to ensure that the requested indexes are in place, and that we don't have
        # any extra indexes that weren't requested.
        _configure_typedef_indexes(typedef)

        # Now our _get_unapplied_migrations() method should return an empty list. If it doesn't,
        # something is wrong.
        if _get_unapplied_migrations(typedef):
            raise DataError('Applying typedef migrations failed.')

def migrate_platform_data_model(options):
    version = get_version_in_use()
    assert version <= VERSION, \
            'Version in use (%d) greater than expected version (%d).' % \
            (version, VERSION)
    if version == VERSION:
        print 'Data model in use matches the current version.'
        return

    for mod in get_migration_modules():
        # it is assumed here that each migration module will have two members:
        # 1. version - an integer value of the version the module migrates to
        # 2. migrate() - a function that performs the migration
        if mod.version <= version:
            continue
        if mod.version > VERSION:
            raise DataError('Migration provided for higher version than is expected.')
        try:
            mod.migrate()
        except Exception, e:
            _log.critical('Migration to data model version %d failed.' %
                          mod.version)
            print >> sys.stderr, \
                    'Migration to version %d failed, see %s for details.' % \
                    (mod.version, options.log_file)
            raise e
        if not options.test:
            set_version(mod.version)
        version = mod.version
    if version < VERSION:
        raise DataError('The current version is still lower than the expected version, even ' +\
            'after migrations were applied.')
    validate_platform_data_model(options)

def validate_platform_data_model(options):
    errors = 0
    if not is_validated():
        errors = validate()
    if errors:
        error_message = '%d errors on validation, see %s for details.'%(errors, options.log_file)
        raise DataError(error_message)
    if not options.test:
        set_validated()

def main():
    options = parse_args()
    start_logging(options)

    if options.force:
        print 'Clearing previous versions.'
        clean_db()

    if options.start is not None:
        last = int(options.start) - 1
        print 'Reverting db to version %d.' % last
        revert_to_version(last)

    try:
        print 'Beginning platform database migration to version %d'%VERSION
        migrate_platform_data_model(options)
        print 'Platform database migration to version %d complete.' % VERSION

        print 'Loading content types.'
        # This call will make sure our ContentTypes collection has entries for all_typedefs, and
        # that their indexes are installed. If they are new, they will automatically have the latest
        # schema version found applied to them.
        load_content_types()
        print 'Content types loaded.'

        print 'Beginning type database migrations.'
        migrate_database_type_models(options)
        print 'Type database migrations complete.'
    except DataError, e:
        _log.critical(str(e))
        _log.critical(''.join(traceback.format_exception(*sys.exc_info())))
        print >> sys.stderr, str(e)
        return os.EX_DATAERR
    except Exception, e:
        _log.critical(str(e))
        _log.critical(''.join(traceback.format_exception(*sys.exc_info())))
        print >> sys.stderr, str(e)
        return os.EX_SOFTWARE

    return os.EX_OK
