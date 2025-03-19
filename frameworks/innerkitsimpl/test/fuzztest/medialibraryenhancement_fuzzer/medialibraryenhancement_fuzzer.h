/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NOTIFYCHANGE_FUZZER_H
#define NOTIFYCHANGE_FUZZER_H

#define FUZZ_PROJECT_NAME "medialibraryenhancement_fuzzer"

#include "userfilemgr_uri.h"
#include "medialibrary_type_const.h"
#include "cloud_enhancement_uri.h"

#include <string>
#include <vector>

namespace OHOS {
namespace Media {
const std::vector<std::string> ENHANCEMENT_FUZZER_URI_LISTS = {
    // PhotoAccessHelper cloud enhancement
    PAH_CLOUD_ENHANCEMENT_ADD,
    PAH_CLOUD_ENHANCEMENT_PRIORITIZE,
    PAH_CLOUD_ENHANCEMENT_CANCEL,
    PAH_CLOUD_ENHANCEMENT_CANCEL_ALL,
    PAH_CLOUD_ENHANCEMENT_SYNC,
    PAH_CLOUD_ENHANCEMENT_QUERY,
    PAH_CLOUD_ENHANCEMENT_GET_PAIR,
};

const std::vector<std::string> MIMETYPE_FUZZER_LISTS = {
    "image/jpeg",
    "image/heif",
};

const std::vector<std::string> DISPLAY_NAME_EXTENSION_FUZZER_LISTS = {
    ".jpg",
    ".hif",
};

uint8_t BUFFER[] = {
    255, 216, 255, 224, 0, 16, 74, 70, 73, 70, 0, 1, 1, 1, 0, 96, 0, 96, 0, 0, 255, 219, 0, 67, 0, 8, 6, 6, 7, 6, 5, 8,
    7, 7, 7, 9, 9, 8, 10, 12, 20, 13, 12, 11, 11, 12, 25, 18, 19, 15, 20, 29, 26, 31, 30, 29, 26, 28, 28, 32, 36, 46,
    39, 32, 34, 44, 35, 28, 28, 40, 55, 41, 44, 48, 49, 52, 52, 52, 31, 39, 57, 61, 56, 50, 60, 46, 51, 52, 50, 255,
    219, 0, 67, 1, 9, 9, 9, 12, 11, 12, 24, 13, 13, 24, 50, 33, 28, 33, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50,
    50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50,
    50, 50, 50, 50, 50, 50, 50, 50, 50, 255, 192, 0, 17, 8, 0, 132, 0, 132, 3, 1, 34, 0, 2, 17, 1, 3, 17, 1, 255, 196,
    0, 31, 0, 0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 255, 196, 0, 181,
    16, 0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 125, 1, 2, 3, 0, 4, 17, 5, 18, 33, 49, 65, 6, 19, 81, 97, 7, 34,
    113, 20, 50, 129, 145, 161, 8, 35, 66, 177, 193, 21, 82, 209, 240, 36, 51, 98, 114, 130, 9, 10, 22, 23, 24, 25, 26,
    37, 38, 39, 40, 41, 42, 52, 53, 54, 55, 56, 57, 58, 67, 68, 69, 70, 71, 72, 73, 74, 83, 84, 85, 86, 87, 88, 89, 90,
    99, 100, 101, 102, 103, 104, 105, 106, 115, 116, 117, 118, 119, 120, 121, 122, 131, 132, 133, 134, 135, 136, 137,
    138, 146, 147, 148, 149, 150, 151, 152, 153, 154, 162, 163, 164, 165, 166, 167, 168, 169, 170, 178, 179, 180, 181,
    182, 183, 184, 185, 186, 194, 195, 196, 197, 198, 199, 200, 201, 202, 210, 211, 212, 213, 214, 215, 216, 217, 218,
    225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 255, 196, 0, 31,
    1, 0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 255, 196, 0, 181, 17, 0,
    2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 119, 0, 1, 2, 3, 17, 4, 5, 33, 49, 6, 18, 65, 81, 7, 97, 113, 19, 34, 50,
    129, 8, 20, 66, 145, 161, 177, 193, 9, 35, 51, 82, 240, 21, 98, 114, 209, 10, 22, 36, 52, 225, 37, 241, 23, 24, 25,
    26, 38, 39, 40, 41, 42, 53, 54, 55, 56, 57, 58, 67, 68, 69, 70, 71, 72, 73, 74, 83, 84, 85, 86, 87, 88, 89, 90, 99,
    100, 101, 102, 103, 104, 105, 106, 115, 116, 117, 118, 119, 120, 121, 122, 130, 131, 132, 133, 134, 135, 136, 137,
    138, 146, 147, 148, 149, 150, 151, 152, 153, 154, 162, 163, 164, 165, 166, 167, 168, 169, 170, 178, 179, 180, 181,
    182, 183, 184, 185, 186, 194, 195, 196, 197, 198, 199, 200, 201, 202, 210, 211, 212, 213, 214, 215, 216, 217, 218,
    226, 227, 228, 229, 230, 231, 232, 233, 234, 242, 243, 244, 245, 246, 247, 248, 249, 250, 255, 218, 0, 12, 3, 1, 0,
    2, 17, 3, 17, 0, 63, 0, 244, 74, 40, 162, 191, 35, 62, 148, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40,
    162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0,
    40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138,
    0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162,
    138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40,
    162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0,
    40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138,
    0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162,
    138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40,
    162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0,
    40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138,
    0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 40, 162,
    138, 0, 40, 162, 138, 0, 40, 162, 138, 0, 255, 217
};
} // namespace Media
} // namespace OHOS
#endif