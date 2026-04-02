/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_ANALYSIS_DEFAULT_COVER_URI_OPERATIONS_H
#define OHOS_MEDIA_ANALYSIS_DEFAULT_COVER_URI_OPERATIONS_H

#include <memory>
#include <string>

#include "medialibrary_album_operations.h"

// LCOV_EXCL_START
namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))

class AnalysisSetDefaultCoverUriOperations {
public:
    static int32_t SetDefaultCoverUri(const string &albumId,
 	  	const string &coverUri);
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIA_ANALYSIS_DEFAULT_COVER_URI_OPERATIONS_H
// LCOV_EXCL_STOP