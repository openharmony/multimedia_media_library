/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_FILEMANAGEMENT_USERFILEMGR_PRIVACY_MANAGER_H
#define OHOS_FILEMANAGEMENT_USERFILEMGR_PRIVACY_MANAGER_H

#include <string>
#include <vector>

namespace OHOS {
namespace Media {
enum PrivacyType {
    PRIVACY_NONE = 0,
    PRIVACY_LOCATION,
    PRIVACY_MAX
};

class MediaPrivacyManager {
public:
    MediaPrivacyManager(const std::string &path, const std::string &mode);
    virtual ~MediaPrivacyManager();

    int32_t Open();

private:
    std::string path_;
    std::string mode_;
    /* Privacy ranges in a file, specified by <begin, end> offsets of the file */
    std::vector<std::pair<uint32_t, uint32_t>> ranges_;
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_FILEMANAGEMENT_USERFILEMGR_PRIVACY_MANAGER_H
