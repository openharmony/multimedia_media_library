/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_DFX_MANAGER_H
#define OHOS_MEDIA_DFX_MANAGER_H

#include <mutex>
#include <string>

#include "dfx_reporter.h"

namespace OHOS {
namespace Media {
class DfxManager {
public:
    DfxManager();
    ~DfxManager();
    static std::shared_ptr<DfxManager> GetInstance();
    void HandleTimeOutOperation(std::string &bundleName, std::string &type, std::string &object, int64_t time);
    void HandleHighMemoryThumbnail(std::string &path, int32_t mediaType, int32_t width, int32_t height);

private:
    void Init();

private:
    static std::mutex instanceLock_;
    static std::shared_ptr<DfxManager> dfxManagerInstance_;
    std::atomic<bool> isInitSuccess_;
    std::shared_ptr<DfxReporter> dfxReporter_;
};
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_DFX_MANAGER_H