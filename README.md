# Cisecurity


The purpose of these scripts is to harden Ubuntu and Debian Linux systems.

cis1804.sh is based on CIS Ubuntu Linux 18.04 LTS Benchmark v2.0.1 from www.cisecurity.org.

cis2004.sh is based on CIS Ubuntu Linux 20.04 LTS Benchmark v1.1.0 from www.cisecurity.org.

cisdebian.sh is based on CIS Debian Family Linux Benchmarks v1.1.0 (Draft) from www.cisecurity.org.

Development started out as a test project for a large Swedish tech company but is now one of my hobies.

Executing this script without update mode (-u) will not make any changes to the operating system.
It will however indicate what would be done if run in update mode.

A file called .cisrc is created when executing this script for the first time.
Edit this file to adjust to server specific requirements.

This software is still a work in progress and should not be run on production systems.

This script is based on CIS IP and the terms are stated below.

Terms of Use at https://www.cisecurity.org/cis-securesuite/cis-securesuite-membership-terms-of-use/, and that page states that "PDF versions of the CIS Benchmarks in accordance with the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International Public License."

"Subject to the terms and conditions of this Public License, the Licensor hereby grants You a worldwide, royalty-free, non-sublicensable, non-exclusive, irrevocable license to exercise the Licensed Rights in the Licensed Material to: reproduce and Share the Licensed Material, in whole or in part, for NonCommercial purposes only; and produce, reproduce, and Share Adapted Material for NonCommercial purposes only."


THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."
