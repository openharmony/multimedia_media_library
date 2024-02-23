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

#include "dfx_reporter.h"

#include "dfx_const.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "hisysevent.h"

namespace OHOS {
namespace Media {
static constexpr char MEDIA_LIBRARY[] = "MEDIALIBRARY";

DfxReporter::DfxReporter()
{
}

DfxReporter::~DfxReporter()
{
}

void DfxReporter::ReportTimeOutOperation(std::string &bundleName, std::string &type, std::string &object, int64_t time)
{
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_TIMEOUT_OPT_ERROR",
        HiviewDFX::HiSysEvent::EventType::FAULT,
        "BUNDLE_NAME", bundleName,
        "OPERATION_TYPE", type,
        "OPERATION_OBJECT", object,
        "TIME", time);
    if (ret != 0) {
        MEDIA_ERR_LOG("ReportTimeoutOperation error:%{public}d", ret);
    }
}

void DfxReporter::ReportHighMemoryImageThumbnail(std::string &path, std::string &suffix, int32_t width, int32_t height)
{
    if (suffix != "jpg" && suffix != "jpeg" && suffix != "jpe") {
        MEDIA_WARN_LOG("image %{public}s is %{public}s, width: %{public}d, height: %{public}d", path.c_str(),
            suffix.c_str(), width, height);
    } else if (width > IMAGE_MIN && height > IMAGE_MIN) {
        MEDIA_WARN_LOG("image %{public}s is too large, width: %{public}d, height: %{public}d", path.c_str(), width,
            height);
    }
}

void DfxReporter::ReportHighMemoryVideoThumbnail(std::string &path, std::string &suffix, int32_t width, int32_t height)
{
    if (width >= VIDEO_8K_MIN || height >= VIDEO_8K_MIN) {
        MEDIA_WARN_LOG("video %{public}s is too large, width: %{public}d, height: %{public}d", path.c_str(), width,
            height);
    }
}
} // namespace Media
} // namespace OHOS