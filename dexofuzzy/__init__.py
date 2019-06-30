# -*- coding: UTF-8 -*-
#
# Copyright (C) 2019 ESTsecurity
#
# This file is part of dexofuzzy.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
'''

'''
# Default packages

# Internal packages
from dexofuzzy.generate_dexofuzzy import GenerateDexofuzzy

# 3rd-party packages


__title__ = 'dexofuzzy'
__version__ = '0.0.2'
__license__ = 'GNU General Public License v2 or later (GPLv2+)'
__copyright__ = 'Copyright (C) 2019 ESTsecurity'


def hash(file_path):
    generateDexoFuzzy = GenerateDexofuzzy()
    report = generateDexoFuzzy.generate_dexofuzzy(file_path)
    return report["dexofuzzy"]


def compare(dexofuzzy_1, dexofuzzy_2):
    generateDexoFuzzy = GenerateDexofuzzy()
    score = generateDexoFuzzy.get_dexofuzzy_compare(dexofuzzy_1, dexofuzzy_2)
    return score
