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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_DIR_ASSET_ASSET_H_
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_DIR_ASSET_ASSET_H_

#include <string>
#include <vector>

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
/**
 * @brief Data class for dir details
 *
 * @since 1.0
 * @version 1.0
 */
class DirAsset {
public:
    EXPORT DirAsset();
    EXPORT virtual ~DirAsset();

    EXPORT void SetDirType(const int32_t dirType);
    EXPORT void SetMediaTypes(const std::string mediaTypes);
    EXPORT void SetDirectory(const std::string directory);
    EXPORT void SetExtensions(const std::string extensions);
    EXPORT int32_t GetDirType() const;
    EXPORT std::string GetMediaTypes() const;
    EXPORT std::string GetDirectory() const;
    EXPORT std::string GetExtensions() const;

private:
    int32_t dirType_;
    std::string mediaTypes_;
    std::string directory_;
    std::string extensions_;
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_INNERKITS_NATIVE_INCLUDE_DIR_ASSET_ASSET_H_
