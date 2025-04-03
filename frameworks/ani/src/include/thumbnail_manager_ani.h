/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_ANI_SRC_INCLUDE_THUMBNAIL_MANAGER_H
#define FRAMEWORKS_ANI_SRC_INCLUDE_THUMBNAIL_MANAGER_H

#include <condition_variable>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "image_type.h"
#include "nocopyable.h"
#include "safe_map.h"
#include "safe_queue.h"
#include "pixel_map.h"
#include "unique_fd.h"
#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))

using PixelMapPtr = std::unique_ptr<PixelMap>;

class MMapFdPtr {
public:
    explicit MMapFdPtr(int32_t fd, bool isNeedRelease);
    ~MMapFdPtr();
    void* GetFdPtr();
    off_t GetFdSize();
    bool IsValid();
private:
    void* fdPtr_ = nullptr;
    off_t size_ = 0;
    bool isValid_ = false;
    bool isNeedRelease_ = false;
};

class ThumbnailManagerAni : NoCopyable {
public:
    virtual ~ThumbnailManagerAni() = default;
    static std::shared_ptr<ThumbnailManagerAni> GetInstance();
    
    EXPORT static std::unique_ptr<PixelMap> QueryThumbnail(const std::string &uriStr,
        const Size &size, const std::string &path);

private:
    ThumbnailManagerAni() = default;
};
} // Media
} // OHOS

#endif // FRAMEWORKS_ANI_SRC_INCLUDE_THUMBNAIL_MANAGER_H
