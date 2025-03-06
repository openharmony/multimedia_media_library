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

class MediaAssetsChangeRequest {
    static { loadLibrary("photo_access_helper_ani"); }

    private nativeMediaAssetsChangeRequestHandleImpl: long = 0;
    
    constructor(context: long) {
        if (this.nativeMediaAssetsChangeRequestHandleImpl == 0) {
            this.nativeMediaAssetsChangeRequestHandleImpl = context;
        }
    }
    
    native static create(): MediaAssetsChangeRequest;
    native SetFavoriteSync(isFavorite : boolean): void;
    native SetHiddenSync(isHidden : boolean): void;
}
