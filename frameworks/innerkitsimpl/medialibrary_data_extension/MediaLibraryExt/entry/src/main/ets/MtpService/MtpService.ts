// @ts-nocheck
import ServiceExtension from '@ohos.application.ServiceExtensionAbility';
import MtpService from '@ohos.multimedia.MtpService'

class MtpServiceExtension extends ServiceExtension{
    onCreate(want) {
        console.log('mtp service onCreate, want:' + want.abilityName);
        MtpService.startMtpService(this.context);
    }

    onRequest(want, startId) {
        console.log('mtp service onRequest, want:' + want.abilityName + ', startId:' + startId);
    }

    onDestroy() {
        console.log('mtp service onDestroy');
        MtpService.stopMtpService(this.context);
    }
}

export default MtpServiceExtension