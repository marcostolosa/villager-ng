def format_anchor_message(anchors):
    """
    Função de formatação de texto para âncoras offline
    :param anchors:
    :return:
    """
    if anchors:
        message_lines = [f"Âncora {anchor.id} - {anchor.location} offline" for anchor in anchors]
        return "\n".join(message_lines)
    else:
        return "Atualmente não há âncoras offline."

# Função de remoção de duplicatas de lista
def list_unique(input_list):
    """
    Função de remoção de duplicatas de lista
    :param input_list:
    :return:
    """
    return list(set(input_list))