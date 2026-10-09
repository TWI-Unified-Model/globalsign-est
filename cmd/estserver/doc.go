/*
Copyright (c) 2020 GMO GlobalSign, Inc.

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
Application estserver is a basic EST server for testing purposes. It provisions
credentials with the mock CA of this fork or, with a tacra section in its
configuration, through the attested resources of draft-novak-lamps-tacra-est
with the TACRA backend (internal/tacra), which forwards to deployed verifiers
and RRPs; estserver.json.example shows that configuration.
*/
package main
