#!/usr/bin/python
#
# Copyright (c) 2011 Red Hat, Inc.
#
#
# This software is licensed to you under the GNU General Public
# License as published by the Free Software Foundation; either version
# 2 of the License (GPLv2) or (at your option) any later version.
# There is NO WARRANTY for this software, express or implied,
# including the implied warranties of MERCHANTABILITY,
# NON-INFRINGEMENT, or FITNESS FOR A PARTICULAR PURPOSE. You should
# have received a copy of GPLv2 along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

#
# Contains mock agent content handlers.
#

import os
import shutil

from pulp.agent.lib.report import *
from pulp.agent.lib.conduit import Conduit

#
# Handlers to be deployed for loader testing
#

# -- Mock RPM Handler --------------------------------------------------------------------

RPM = dict(
name='rpm',
descriptor="""
[main]
enabled=1
module=

[types]
system=Linux
content=rpm
bind=yum

[rpm]
class=RpmHandler
xxx=hello
yyy=world

[yum]
class=YumHandler

[Linux]
class=LinuxHandler
""",
handler=
"""
from pulp.agent.lib.handler import *
from pulp.agent.lib.report import *
from pulp.agent.lib.conduit import *

class RpmHandler(ContentHandler):

  def install(self, conduit, units, options):
    assert(self.cfg['xxx'] == 'hello')
    assert(self.cfg['yyy'] == 'world')
    assert(isinstance(conduit, Conduit))
    assert(isinstance(units, list))
    assert(isinstance(options, dict))
    report = HandlerReport()
    report.succeeded({}, len(units))
    return report

  def update(self, conduit, units, options):
    assert(isinstance(conduit, Conduit))
    assert(isinstance(units, list))
    assert(isinstance(options, dict))
    report = HandlerReport()
    report.succeeded({}, len(units))
    return report

  def uninstall(self, conduit, units, options):
    assert(isinstance(conduit, Conduit))
    assert(isinstance(units, list))
    assert(isinstance(options, dict))
    report = HandlerReport()
    report.succeeded({}, len(units))
    return report

  def profile(self, conduit):
    assert(isinstance(conduit, Conduit))
    return ProfileReport()

class YumHandler(BindHandler):

  def bind(self, conduit, definitions):
    assert(isinstance(conduit, Conduit))
    assert(isinstance(definitions, list))
    report = BindReport()
    report.succeeded({}, 1)
    return report

  def rebind(self, conduit, definitions):
    assert(isinstance(conduit, Conduit))
    assert(isinstance(definitions, list))
    report = BindReport()
    report.succeeded({}, 1)
    return report

  def unbind(self, conduit, repo_id):
    assert(isinstance(conduit, Conduit))
    assert(isinstance(repo_id, (int,str)))
    report = BindReport()
    report.succeeded({}, 1)
    return report

  def clean(self, conduit):
    assert(isinstance(conduit, Conduit))
    report = CleanReport()
    report.succeeded({}, 1)
    return report

class LinuxHandler(SystemHandler):

  def reboot(self, conduit, options):
    assert(isinstance(conduit, Conduit))
    assert(isinstance(options, dict))
    report = RebootReport()
    report.succeeded()
    return report
""")


# -- Mock SRPM Handler -------------------------------------------------------------------

SRPM = dict(
name='srpm',
descriptor="""
[main]
enabled=1

[types]
content=srpm

[srpm]
class=test.handlers.srpm.SRpmHandler

""",
handler=
"""
from pulp.agent.lib.handler import *
from pulp.agent.lib.report import *
from pulp.agent.lib.conduit import *

class SRpmHandler(ContentHandler):

  def install(self, conduit, units, options):
    assert(isinstance(conduit, Conduit))
    assert(isinstance(units, list))
    assert(isinstance(options, dict))
    report = HandlerReport()
    report.succeeded({}, len(units))
    return report

  def update(self, conduit, units, options):
    assert(isinstance(conduit, Conduit))
    assert(isinstance(units, list))
    assert(isinstance(options, dict))
    report = HandlerReport()
    report.succeeded({}, len(units))
    return report

  def uninstall(self, conduit, units, options):
    assert(isinstance(conduit, Conduit))
    assert(isinstance(units, list))
    assert(isinstance(options, dict))
    report = HandlerReport()
    report.succeeded({}, len(units))
    return report
""")

# -- Mock (section missing) Handler ------------------------------------------------------

SECTION_MISSING = dict(
name='Test_section_not_found',
descriptor="""
[main]
enabled=1
module=

[types]
content=puppet
""",
handler="""
class A: pass
""")


# -- Mock (class not defined) Handler ----------------------------------------------------

CLASS_NDEF = dict(
name='Test-class-property-missing',
descriptor="""
[main]
enabled=1
module=
[types]
content=puppet
[puppet]
foo=bar
""",
handler="""
class A: pass
""")

#
# Mock Deployer
#

class MockDeployer:

    ROOT = '/tmp/pulp-test'
    CONF_D = os.path.join(ROOT, 'etc/agent/handler')
    PATH = os.path.join(ROOT, 'usr/lib/agent/handler')
    SITE_PACKAGES = os.path.join(ROOT, 'site-packages')
    PACKAGE = 'test.handlers'

    def deploy(self):
        for path in (self.CONF_D, self.PATH, self.SITE_PACKAGES):
            shutil.rmtree(path, ignore_errors=True)
            os.makedirs(path)
        self.build_site_packages()
        sys.path.insert(0, self.SITE_PACKAGES)
        for handler in (RPM, SRPM, SECTION_MISSING, CLASS_NDEF):
            self.__deploy(handler)
        print 'deployed'
    
    def clean(self):
        shutil.rmtree(self.ROOT, ignore_errors=True)
    
    def __deploy(self, handler):
        name = handler['name']
        mod = os.path.join(self.PATH, '%s.py' % name)
        descriptor = \
            handler['descriptor'].replace('module=', 'module=%s' % mod)
        fn = '.'.join((name, 'conf'))
        path = os.path.join(self.CONF_D, fn)
        # deploy descriptor
        f = open(path, 'w')
        f.write(descriptor)
        f.close()
        # deploy module
        fn = '.'.join((name, 'py'))
        if 'module=' not in descriptor:
            pkgpath = os.path.join(*self.PACKAGE.split('.'))
            rootdir = os.path.join(self.SITE_PACKAGES, pkgpath)
        else:
            rootdir = self.PATH
        path = os.path.join(rootdir, fn)
        f = open(path, 'w')
        f.write(handler['handler'])
        f.close()

    def build_site_packages(self):
        history = [self.SITE_PACKAGES]
        for p in self.PACKAGE.split('.'):
            history.append(p)
            pkgdir = os.path.join(*history)
            os.makedirs(pkgdir)
            path = os.path.join(pkgdir, '__init__.py')
            f = open(path, 'w')
            f.write('# package:%s' % p)
            f.close()
