// @flow
import * as React from 'react'
import {Avatar, Box, ClickableBox, Icon, Text} from '../../../common-adapters'
import {globalMargins, globalStyles, isMobile} from '../../../styles'

type SmallProps = {
  teamname: string,
  participantCount: number,
  onClick: () => void,
  onClickGear: () => void,
}

const gearIconSize = isMobile ? 24 : 16

const SmallTeamHeader = ({canManage, teamname, participantCount, onClick, onClickGear}: SmallProps) => (
  <ClickableBox
    style={{
      ...globalStyles.flexBoxRow,
      alignItems: 'center',
      marginLeft: globalMargins.small,
    }}
    onClick={evt => !evt.defaultPrevented && onClick()}
  >
    <Avatar size={isMobile ? 48 : 32} teamname={teamname} isTeam={true} />
    <Box style={{...globalStyles.flexBoxColumn, flex: 1, marginLeft: globalMargins.small}}>
      <Text type="BodySemibold">{teamname}</Text>
      <Box style={globalStyles.flexBoxRow}>
        <Text type="BodySmall">
          {participantCount.toString() + ' member' + (participantCount !== 1 ? 's' : '')}
        </Text>
      </Box>
    </Box>
    <Icon
      type="iconfont-gear"
      onClick={evt => {
        evt.preventDefault()
        onClickGear()
      }}
      style={{marginRight: 16, width: gearIconSize, height: gearIconSize, fontSize: gearIconSize}}
    />
  </ClickableBox>
)

type BigProps = {
  channelname: string,
  description: ?string,
  teamname: string,
  onClick: () => void,
}

const BigTeamHeader = (props: BigProps) => {
  return (
    <Box style={{...globalStyles.flexBoxColumn, alignItems: 'stretch'}}>
      <Text style={{alignSelf: 'center', marginTop: globalMargins.medium, marginBottom: 2}} type="BodyBig">
        #{props.channelname}
      </Text>
      {props.description && (
        <Text
          style={{
            paddingLeft: 4,
            paddingRight: 4,
            textAlign: 'center',
          }}
          type="Body"
        >
          {props.description}
        </Text>
      )}
    </Box>
  )
}

export {SmallTeamHeader, BigTeamHeader}
