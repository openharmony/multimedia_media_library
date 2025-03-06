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

import { PhotoAssetHandle } from "./photo_asset.ets";
import { AlbumHandle } from "./photo_album.ets";

export class BusinessError<T = void> {
    code: number = 0;
    data?: T;
}

export type AsyncCallback<T, E = void> = (err: BusinessError<E>, data?: T) => void;

export class FetchResultHandle<T> {
    static { loadLibrary("ani_photo_access_helper"); }
    private nativeValue: long = 0;

    constructor(value: long) {
        this.nativeValue = value;
    }

    native getAllObjects(): Array<PhotoAssetHandle> | Array<AlbumHandle>;
    native getFirstObject(): PhotoAssetHandle | AlbumHandle;
    native getNextObject(): PhotoAssetHandle | AlbumHandle;
    native getCount():number;
    native close(): void
}