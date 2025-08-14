/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CLOUD_MEDIA_DAO_UTILS_H
#define OHOS_CLOUD_MEDIA_DAO_UTILS_H

#include <string>
#include <vector>

namespace OHOS::Media::CloudSync {
#define EXPORT __attribute__ ((visibility ("default")))
class EXPORT CloudMediaDaoUtils {
public:
    static std::string ToStringWithCommaAndQuote(const std::vector<std::string> &values);
    static std::string ToStringWithComma(const std::vector<std::string> &fileIds);
    static std::string FillParams(const std::string &sql, const std::vector<std::string> &bindArgs);
    static std::vector<std::string> GetNumbers(const std::vector<std::string> &albumIds);
    static std::vector<std::string> GetStringVector(const std::vector<int32_t> &intVals);
    static int32_t ToInt32(const std::string &str);
    static std::string VectorToString(const std::vector<uint64_t> &vec, const std::string &sep = ", ");
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_CLOUD_MEDIA_DAO_UTILS_H
