/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef INTERFACE_INNERKIT_NATIVE_INCLUDE_INTIMACY_SIMILARITY_H
#define INTERFACE_INNERKIT_NATIVE_INCLUDE_INTIMACY_SIMILARITY_H

#include <cstdint>
#include <nlohmann/json.hpp>

namespace OHOS {
namespace Media {

class IntimacySimilarity {
public:
    IntimacySimilarity();
    IntimacySimilarity(const int32_t albumId, const float similarity);

private:
    int32_t albumId_;
    float similarity_{0};

    friend void to_json(nlohmann::json &data, const IntimacySimilarity similarity)
    {
        data["albumId"] = similarity.albumId_;
        data["similarity"] = similarity.similarity_;
    }
};

} // namespace Media
} // namespace OHOS

#endif // INTERFACE_INNERKIT_NATIVE_INCLUDE_INTIMACY_SIMILARITY_H