import styled from 'styled-components'
import { Button, Flex, Heading, Text, LogoIcon } from '@pancakeswap/uikit'
import Page from 'components/Layout/Page'
import { useTranslation } from 'contexts/Localization'
import Link from 'next/link'
import PageSection from 'components/PageSection'
import HeroNft from '../views/Home/components/HeroNft'

const textBox: React.CSSProperties = {
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'center',
  justifyContent: 'center',
  textAlign: 'center',
  backgroundColor: 'rgba(100, 100, 100, 0.3)',
  borderRadius: '25px',
  border: '1px solid lightgray',
  padding: '10px',
}

const NFTsPage = () => {
  const { t } = useTranslation()
  const HomeSectionContainerStyles = { margin: '0', width: '100%', maxWidth: '1100px' }

  return (
    <Page>
      <div style={{ textAlign: 'center' }}>
        <Heading scale="xxl">Coming Soon!</Heading>
        <Text mb="16px">{t('This page is under development')}</Text>
      </div>
      <PageSection
        innerProps={{ style: HomeSectionContainerStyles }}
        containerProps={{
          id: 'home-4',
        }}
        index={2}
        hasCurvedDivider={false}
      >
        <HeroNft />
      </PageSection>
      <div style={{ textAlign: 'center' }}>
        <Link href="/" passHref>
          <Button as="a" scale="sm">
            {t('Back Home')}
          </Button>
        </Link>
      </div>
    </Page>
  )
}

export default NFTsPage
