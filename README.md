# chromium-password-decryptor
Chromium v80+ password & decryptor, supports user profile

Chromium based browser password and cookies decryptor.
It support user profiles like "Profile 1" , "Profile 2" , etc.
For other chromium based browser, change browser path in source.

**Note**: This program is vulnerable to heap overflow. 
The decrypted data is stored in heap, 512KB is allocated for passwords and 2MB for cookies per profile.
In normal cases, it should work.

*Pull requests* are welcome. The author had no intention to make it stealth, undetectable from AV's.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
