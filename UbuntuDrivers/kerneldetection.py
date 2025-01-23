#
#       kerneldetection.py
#
#       Copyright 2013 Canonical Ltd.
#
#       Author: Alberto Milone <alberto.milone@canonical.com>
#
#       This program is free software; you can redistribute it and/or modify
#       it under the terms of the GNU General Public License as published by
#       the Free Software Foundation; either version 2 of the License, or
#       (at your option) any later version.
#
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       GNU General Public License for more details.
#
#       You should have received a copy of the GNU General Public License
#       along with this program; if not, write to the Free Software
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#       MA 02110-1301, USA.

import apt_pkg
import logging
import re
import os
from subprocess import Popen, PIPE


class KernelDetection(object):

    def __init__(self, cache=None):
        if cache:
            self.apt_cache = cache
            self.apt_depcache = apt_pkg.DepCache(cache)
        else:
            apt_pkg.init_config()
            apt_pkg.init_system()
            self.apt_cache = apt_pkg.Cache(None)
            self.apt_depcache = apt_pkg.DepCache(cache)

    def _is_greater_than(self, term1, term2):
        # We don't want to take into account
        # the flavour
        pattern = re.compile('(.+)-([0-9]+)-(.+)')
        match1 = pattern.match(term1)
        match2 = pattern.match(term2)
        if match1:
            term1 = '%s-%s' % (match1.group(1),
                               match1.group(2))
            term2 = '%s-%s' % (match2.group(1),
                               match2.group(2))

        logging.debug('Comparing %s with %s' % (term1, term2))
        command = 'dpkg --compare-versions %s gt %s' % \
                  (term1, term2)
        process = Popen(command.split(' '))
        process.communicate()
        return not process.returncode

    def _get_linux_flavour(self, candidates, image):
        pattern = re.compile(r'linux-image-([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)-(.+)')
        match = pattern.match(image)
        flavour = ''
        if match:
            flavour = match.group(3)

        return flavour

    def _filter_cache(self, pkg):
        package_name = pkg.name
        if (package_name.startswith('linux-image') and
            'extra' not in package_name and (pkg.current_ver or
                                             self.apt_depcache.marked_install(pkg))):
            return package_name
        else:
            return None

    def _get_linux_metapackage(self, target):
        '''Get the linux headers, linux-image or linux metapackage'''
        metapackage = ''
        image_package = ''
        version = ''
        prefix = 'linux-%s' % ('headers' if target == 'headers' else 'image')

        pattern = re.compile('linux-image-(?:unsigned-)?(.+)-([0-9]+)-(.+)')

        for package_name in map(self._filter_cache, self.apt_cache.packages):
            if package_name:
                match = pattern.match(package_name)
                # Here we filter out packages other than
                # the actual image or header packages
                if match:
                    current_package = match.group(0)
                    current_version = '%s-%s' % (match.group(1),
                                                 match.group(2))
                    # See if the current version is greater than
                    # the greatest that we've found so far
                    if self._is_greater_than(current_version,
                                             version):
                        version = current_version
                        image_package = current_package

        if version:
            if target == 'headers':
                target_package = image_package.replace('image', 'headers')
            else:
                target_package = image_package

            # Look for all possible metapackage variants (e.g. linux-image-generic, linux-image-hwe-generic)
            metapackage_patterns = [
                'linux-%s-%s',  # standard pattern (e.g. linux-image-generic)
                'linux-%s-hwe-%s',  # HWE pattern (e.g. linux-image-hwe-generic)
                'linux-%s-oem-%s',  # OEM pattern (e.g. linux-image-oem-generic)
                'linux-%s-lowlatency-%s',  # lowlatency pattern
            ]

            # Get the flavor from the target package
            flavor = self._get_linux_flavour([], target_package)
            if not flavor:
                return metapackage

            # Try all possible metapackage patterns
            for pattern in metapackage_patterns:
                candidate = pattern % (prefix, flavor)
                try:
                    pkg = self.apt_cache[candidate]
                    if pkg.current_ver or self.apt_depcache.marked_install(pkg):
                        metapackage = candidate
                        break
                except KeyError:
                    continue

            # If no specific variant found, try to find any reverse dependency that matches our prefix
            if not metapackage:
                reverse_dependencies = [dep.parent_pkg.name for dep in self.apt_cache[target_package]
                                        .rev_depends_list if dep.parent_pkg.name.startswith(prefix)]

                if reverse_dependencies:
                    # This should be something like linux-image-$flavour
                    # or linux-headers-$flavour
                    metapackage = ''
                    for candidate in reverse_dependencies:
                        try:
                            candidate_pkg = self.apt_cache[candidate]
                            if (candidate.startswith(prefix) and (candidate_pkg and
                               (candidate_pkg.current_ver or self.apt_depcache.marked_install(candidate_pkg))) and
                               candidate.replace(prefix, '') > metapackage.replace(prefix, '')):
                                metapackage = candidate
                        except KeyError:
                            continue

                    # if we are looking for headers, then we are good
                    if target == 'meta':
                        # Let's get the metapackage
                        reverse_dependencies = [dep.parent_pkg.name for dep in self.apt_cache[metapackage]
                                                .rev_depends_list if dep.parent_pkg.name.startswith('linux-')]
                        if reverse_dependencies:
                            flavor = self._get_linux_flavour(reverse_dependencies, target_package)
                            linux_meta = ''
                            for meta in reverse_dependencies:
                                # For example linux-generic-hwe-20.04
                                if meta.startswith('linux-%s-' % (flavor)):
                                    linux_meta = meta
                                    break
                            # This should be something like linux-$flavour
                            if not linux_meta:
                                # Try the 1st reverse dependency
                                metapackage = reverse_dependencies[0]
                            else:
                                metapackage = linux_meta
        return metapackage

    def get_linux_headers_metapackage(self):
        '''Get the linux headers for the newest_kernel installed'''
        return self._get_linux_metapackage('headers')

    def get_linux_image_metapackage(self):
        '''Get the linux headers for the newest_kernel installed'''
        return self._get_linux_metapackage('image')

    def get_linux_metapackage(self):
        '''Get the linux metapackage for the newest_kernel installed'''
        return self._get_linux_metapackage('meta')

    def get_linux_version(self):
        linux_image_meta = self.get_linux_image_metapackage()
        linux_version = ''
        try:
            # dependencies = self.apt_cache[linux_image_meta].candidate.\
            #                  record['Depends']
            candidate = self.apt_depcache.get_candidate_ver(self.apt_cache[linux_image_meta])
            for dep_list in candidate.depends_list_str.get('Depends'):
                for dep_name, dep_ver, dep_op in dep_list:
                    if dep_name.startswith('linux-image'):
                        linux_version = dep_name.strip().replace('linux-image-', '')
                        break
        except KeyError:
            logging.error('No dependencies can be found for %s' % (linux_image_meta))
            return None

        # if ', ' in dependencies:
        #     deps = dependencies.split(', ')
        #     for dep in deps:
        #         if dep.startswith('linux-image'):
        #             linux_version = dep.replace('linux-image-', '')
        # else:
        #     if dependencies.strip().startswith('linux-image'):
        #         linux_version = dependencies.strip().replace('linux-image-', '')

        return linux_version

    def get_running_kernel_version(self):
        '''Get the version of the currently running kernel'''
        try:
            process = Popen(['uname', '-r'], stdout=PIPE, stderr=PIPE)
            output, _ = process.communicate()
            return output.decode('utf-8').strip()
        except Exception as e:
            logging.error('Failed to get running kernel version: %s' % str(e))
            return None

    def _parse_kernel_version(self, version):
        '''Parse Ubuntu kernel version into its components
        Example: 6.11.0-13-generic-64k -> 
        {
            'upstream': '6.11.0',
            'abi': '13',
            'flavor': 'generic',
            'variant': '64k'  # optional
        }
        '''
        # Match patterns like: 6.11.0-13-generic or 6.11.0-13-generic-64k
        pattern = re.compile(r'^(\d+\.\d+\.\d+)-(\d+)-([^-]+)(?:-(.+))?$')
        match = pattern.match(version)
        if not match:
            return None
        
        return {
            'upstream': match.group(1),
            'abi': match.group(2),
            'flavor': match.group(3),
            'variant': match.group(4) if match.group(4) else ''
        }

    def is_running_kernel_outdated(self):
        '''Check if the running kernel is outdated by checking if the installed kernel
        metapackage has an update available.
        
        Returns:
            tuple: (is_outdated, running_version, latest_version, requires_dkms)
            - is_outdated: True if a newer kernel is available
            - running_version: Current running kernel version
            - latest_version: Latest available kernel version (if any)
            - requires_dkms: True if the running kernel requires DKMS modules
        '''
        running_version = self.get_running_kernel_version()
        if not running_version:
            return False, None, None, False

        # Parse the running kernel version
        running_parts = self._parse_kernel_version(running_version)
        if not running_parts:
            # Non-standard kernel version format, DKMS would be required
            logging.debug('Non-standard kernel version detected: %s - DKMS would be required' % running_version)
            return False, running_version, None, True

        try:
            # First run apt update
            update_process = Popen(['apt', 'update'], stdout=PIPE, stderr=PIPE)
            _, update_err = update_process.communicate()
            if update_process.returncode != 0:
                logging.warning('apt update failed: %s' % update_err.decode('utf-8'))

            # Find the installed kernel metapackage
            process = Popen(['apt', 'list', '--installed'], stdout=PIPE, stderr=PIPE)
            installed_output, _ = process.communicate()
            installed_output = installed_output.decode('utf-8')

            # Look for any linux-image-* metapackage
            meta_pkg = None
            for line in installed_output.splitlines():
                pkg_name = line.split('/')[0]
                if pkg_name.startswith('linux-image-'):
                    # Skip the actual kernel image packages (both regular and unsigned), we want the metapackages
                    if not re.match(r'linux-image-(\d+\.\d+\.\d+-\d+|\w*unsigned-\d+\.\d+\.\d+-\d+)', pkg_name):
                        meta_pkg = pkg_name
                        logging.debug('Found kernel metapackage: %s' % meta_pkg)
                        break

            if not meta_pkg:
                logging.debug('No kernel metapackage found: - DKMS would be required')
                return False, running_version, None, True

            # Check if the metapackage has an update
            process = Popen(['apt', 'list', '--upgradable'], stdout=PIPE, stderr=PIPE)
            upgradable_output, _ = process.communicate()
            upgradable_output = upgradable_output.decode('utf-8')

            # Look for the metapackage in the upgradable list
            latest_version = None
            for line in upgradable_output.splitlines():
                if line.startswith(meta_pkg + '/'):
                    logging.debug('Found upgradable metapackage: %s' % line)
                    # Get the version it depends on from the package name
                    try:
                        pkg = self.apt_cache[meta_pkg]
                        candidate = self.apt_depcache.get_candidate_ver(pkg)
                        if not candidate:
                            continue
                        
                        # Look through dependencies to find the actual kernel version
                        for dep_list in candidate.depends_list.get('Depends', []):
                            for dep in dep_list:
                                if dep.target_pkg.name.startswith('linux-image-') and \
                                   not dep.target_pkg.name == meta_pkg:
                                    version = dep.target_pkg.name.replace('linux-image-', '')
                                    version_parts = self._parse_kernel_version(version)
                                    if version_parts:
                                        latest_version = version
                                        logging.debug('Found new kernel version: %s' % latest_version)
                                        break
                    except (KeyError, AttributeError) as e:
                        logging.debug('Error checking metapackage dependencies: %s' % str(e))
                        continue

            if latest_version and latest_version != running_version:
                logging.debug('Kernel update available: %s -> %s' % (running_version, latest_version))
                return True, running_version, latest_version, False

        except Exception as e:
            logging.error('Error checking kernel version: %s' % str(e))
            return False, running_version, None, False

        logging.debug('Kernel is up to date: %s' % running_version)
        return False, running_version, None, False

    def get_kernel_update_warning(self):
        '''Get a warning message if the kernel needs updating.
        
        Returns:
            tuple: (message, should_exit)
            - message: Warning message if any, None otherwise
            - should_exit: True if we should exit (e.g., when DKMS is required but not enabled)
        '''
        is_outdated, running, latest, requires_dkms = self.is_running_kernel_outdated()
        
        if requires_dkms:
            return ("Your running kernel (%s) requires DKMS modules. "
                   "Please use --include-dkms if you want to proceed." % running,
                   True)
        
        if is_outdated and latest:
            return (f"Warning: Your running kernel ({running}) is outdated. "
                    f"A newer kernel ({latest}) is available in the Ubuntu archives. "
                    f"Please run 'sudo apt update && sudo apt upgrade' to update your system.",
                    False)
                    
        return None, False

    def dump_cache(self):
        '''Print all package names and their versions from the apt cache'''
        for pkg in sorted(self.apt_cache.packages, key=lambda p: p.name):
            ver = pkg.current_ver.ver_str if pkg.current_ver else 'not installed'
            print(f"{pkg.name}: {ver}")
