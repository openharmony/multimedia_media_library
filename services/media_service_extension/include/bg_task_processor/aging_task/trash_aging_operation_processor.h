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

#ifndef TRASH_AGING_OPERATION_PROCESSOR_H
#define TRASH_AGING_OPERATION_PROCESSOR_H

#include "medialibrary_base_bg_processor.h"

#include <string>

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class TrashAgingOperationProcessor final : public MediaLibraryBaseBgProcessor {
public:
    TrashAgingOperationProcessor() {}
    ~TrashAgingOperationProcessor() {}

    int32_t Start(const std::string &taskExtra) override;
    int32_t Stop(const std::string &taskExtra) override;

private:
    void DoAgingOperation();
    void CacheAging();
    void ClearInvalidDeletedAlbum();
    void TrashStartWork();
    void TrashInterruptWork();
    int32_t DoTrashAging(std::shared_ptr<int> countPtr);

    const std::string taskName_ = TRASH_AGING_OPERATION;
    bool taskStop_ {false};
};
} // namespace Media
} // namespace OHOS
#endif  // TRASH_AGING_OPERATION_PROCESSOR_H
